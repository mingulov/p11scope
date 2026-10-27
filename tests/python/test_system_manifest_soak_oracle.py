#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""M13 system--manifest soak oracle twins: healthy and failing evidence.

The M13 vehicle (scripts/system-manifest-soak.sh) runs one long
`inventory --system --manifest` capture over owned SoftHSM workloads
and the oracle (scripts/system-manifest-soak-oracle.py) judges the
evidence directory into a verdict. Six fail-closed gates:

- finite_stop: the observer exited 0 on its own with a report whose
  observation window closed.
- workload_ledger: every workload finished (DONE status=ok) and its
  post-gate LEDGER call totals equal the report's per-caller edge
  entries on the owned provider copy exactly; no foreign caller holds
  edges on that copy.
- loss_accounting: no silent loss — the semantic stop line conserves
  (collected == joined + shed), every nonzero shed/refused/unrouted
  count has a named gap, every gap is named (subject + reason), and
  gaps_suppressed == 0.
- resource_accounting: the 1 Hz RSS/FD trace spans the window, RSS
  stays within 256 MiB, and neither RSS nor FDs grow steadily.
- journal_disclosure: key operations stay honestly unavailable with
  the journal_unavailable reason (0.5.1 scope).
- clean_exit: observer, sampler and every workload exited 0.

Healthy and failing twins run unignored with small owned inputs only:
no observer, no SoftHSM, no privilege. Each red leg flips exactly one
gate so a passing suite proves every gate measures.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "system-manifest-soak-oracle.py"

GO = 1_000_000_000
PIDS = (5001, 5002)
CALLS_MAIN = 500
CALLS_TEARDOWN = 13
CALLS_SETUP = 11


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except OSError:
        return None


ORACLE = _load("system_manifest_soak_oracle", ORACLE_PATH)


def require_oracle(test):
    """Fail naming the missing oracle (RED) or return the module."""
    if ORACLE is None:
        test.fail(f"soak oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


def _workload_log(pid, cell, module, main=CALLS_MAIN,
                  teardown=CALLS_TEARDOWN, setup=CALLS_SETUP, status="ok"):
    lines = [f"READY cell={cell} pid={pid} start=111 gen=0 exe=/work/workload"]
    base = (f"cell={cell} pid={pid} start=111 gen=0 exe=/work/workload "
            f"module={module}")
    rows = [("C_Initialize", "-", setup, "setup", GO - 30_000_000_000, GO - 29_000_000_000),
            ("C_Sign", "0x1081", main, "main", GO + 1_000_000_000, GO + 100_000_000_000),
            ("C_CloseSession", "-", teardown, "teardown",
             GO + 101_000_000_000, GO + 102_000_000_000)]
    for fn, mech, count, phase, t0, t1 in rows:
        lines.append(f"LEDGER {base} fn={fn} mech={mech} n={count} bad=0 "
                     f"phase={phase} t0={t0} t1={t1}")
    lines.append(f"DONE cell={cell} pid={pid} start=111 gen=0 exe=/work/workload "
                 f"status={status}")
    return "\n".join(lines) + "\n"


def _resources(rows):
    out = ["# ms rss_kb hwm_kb fds"]
    out.extend(f"{ms} {rss} {hwm} {fds}" for ms, rss, hwm, fds in rows)
    return "\n".join(out) + "\n"


def make_green(root, *, horizon=1800, callers=PIDS, mode="live",
               shed=0, refused=0, unrouted=0, gaps=()):
    """Write a fully green fixture evidence directory; legs mutate copies."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    module = str(root / "provider" / "libsofthsm2-owned.so")
    end = GO + horizon * 1_000_000_000 + 60_000_000_000
    workloads = []
    caller_rows = []
    edge_rows = []
    for index, pid in enumerate(callers):
        cell = f"W{index}"
        (root / f"workload-{index}.log").write_text(
            _workload_log(pid, cell, module), encoding="utf-8")
        workloads.append({"pid": pid, "starttime": 111,
                          "log": f"workload-{index}.log", "exit": 0})
        caller_rows.append({"id": f"c{index}", "pid": pid})
        edge_rows.append({
            "caller": f"c{index}", "module": "m0",
            "entries": {
                "count": CALLS_MAIN + CALLS_TEARDOWN,
                "coverage": {"state": "counted", "since_ns": GO,
                             "until_ns": end, "first_ns": None,
                             "lossy": False, "reason": None, "detail": None},
            },
        })
    joined = len(callers) * 40
    collected = joined + shed
    (root / "observer.stderr").write_text(
        f"p11scope: pass 0: attached\n"
        f"p11scope: semantic calls: collected {collected}, joined {joined}, "
        f"shed {shed}, bindings {len(callers)}, refused {refused}\n",
        encoding="utf-8")
    step_ms = (horizon + 60) * 1000 // 120
    (root / "resources.tsv").write_text(
        _resources([(n * step_ms, 52_000 + (n % 7), 54_000, 40)
                    for n in range(121)]),
        encoding="utf-8")
    report = {
        "scope": "system",
        "observation": {
            "started_ns": GO - 5_000_000_000, "ended_ns": end,
            "passes": 12,
            "semantic_capture": {
                "status": "active", "admitted_endpoints": 30,
                "refused_endpoints": 0, "continuity_cuts": 0,
                "unrouted_returns": unrouted, "stop_quiescence": "quiesced",
                "final_drain": True,
            },
        },
        "budgets": {
            "callers": {"limit": 4096, "occupied": len(callers), "refused": 0},
            "modules": {"limit": 4096, "occupied": 1, "refused": 0},
            "edges": {"limit": 32768, "occupied": len(callers), "refused": 0},
            "endpoints": {"limit": 4096, "occupied": 30, "refused": 0},
            "counters": {"cap": 1 << 62, "observed_edges": len(callers),
                         "saturated_edges": 0},
        },
        "callers": caller_rows,
        "modules": [{"id": "m0", "paths": [module]}],
        "edges": edge_rows,
        "semantic_edges": [],
        "object_observations": {"status": "unavailable",
                                "reason": "journal_unavailable"},
        "gaps": [{"subject": subject, "reason": reason} for subject, reason in gaps],
        "gaps_suppressed": 0,
    }
    (root / "report.json").write_text(json.dumps(report), encoding="utf-8")
    if mode == "live":
        installed = {"path": str(root / "p11scope"), "sha256_pre": "a" * 64,
                     "sha256_post": "a" * 64, "size": 64}
        stub = None
    else:
        installed = None
        stub = {"path": str(root / "stub.py"), "sha256": "c" * 64}
    run = {
        "schema": "p11scope/manifest-soak-run/v1",
        "cell_id": "soak-manifest.1800s", "mode": mode,
        "horizon_s": horizon, "require_duration_s": horizon,
        "observer_duration_s": horizon + 60, "callers": len(callers),
        "provider_copy": module, "workloads": workloads,
        "observer": {"exit": 0, "signal": None, "timed_out": False},
        "sampler": {"exit": 0, "signal": None},
        "timing": {"t_go_mono_ns": GO, "start_mono_ns": GO, "end_mono_ns": end},
        "installed": installed, "stub": stub,
        "artifacts": {"run": "run.json", "report": "report.json",
                      "resources": "resources.tsv", "stderr": "observer.stderr"},
    }
    (root / "run.json").write_text(json.dumps(run), encoding="utf-8")
    return root


def mutate_copy(base, name, mutate):
    target = base.parent / name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(base, target)
    mutate(target)
    return target


def rewrite_json(path, transform):
    path = Path(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    transform(value)
    path.write_text(json.dumps(value), encoding="utf-8")


class SoakOracleTest(unittest.TestCase):
    def setUp(self):
        self.oracle = require_oracle(self)
        self.tmp = tempfile.TemporaryDirectory(prefix="manifest-soak-twins-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.green = make_green(self.base / "green")

    def evaluate(self, directory):
        return self.oracle.evaluate(directory)

    def assert_gate(self, verdict, name, expected):
        self.assertEqual(verdict["gates"][name]["pass"], expected,
                         f"gate {name}: {verdict['gates'][name]['detail']}")

    def assert_red_only(self, verdict, name):
        self.assertEqual(verdict["verdict"], "FAIL")
        for gate in self.oracle.GATES:
            self.assert_gate(verdict, gate, gate != name)

    def test_green_control_passes_and_qualifies(self):
        verdict = self.evaluate(self.green)
        self.assertEqual(verdict["verdict"], "PASS", json.dumps(verdict["gates"]))
        self.assertTrue(verdict["qualifying"])
        for gate in self.oracle.GATES:
            self.assert_gate(verdict, gate, True)

    def test_green_short_horizon_passes(self):
        short = make_green(self.base / "short", horizon=300)
        verdict = self.evaluate(short)
        self.assertEqual(verdict["verdict"], "PASS", json.dumps(verdict["gates"]))

    def test_green_named_shed_is_accounted(self):
        counted = make_green(
            self.base / "shed", shed=100, gaps=[("semantic calls unrouted", "first burst")])
        verdict = self.evaluate(counted)
        self.assertEqual(verdict["verdict"], "PASS", json.dumps(verdict["gates"]))

    def test_green_dry_run_passes_but_never_qualifies(self):
        dry = make_green(self.base / "dry", horizon=8, mode="dry-run")
        verdict = self.evaluate(dry)
        self.assertEqual(verdict["verdict"], "PASS", json.dumps(verdict["gates"]))
        self.assertFalse(verdict["qualifying"])

    def test_stub_emits_entry_coverage_for_ledger_join(self):
        dry = make_green(self.base / "stub", horizon=8, mode="dry-run")
        manifest = dry / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "fixtures" /
                                       "system-manifest-soak-stub.py"),
             "inventory", "--system", "--manifest", str(manifest),
             "--duration", "1", "--attach-delay", "0", "--json",
             "-o", str(dry / "report.json"),
             "--loopback-log", str(dry / "workload-0.log"),
             "--loopback-log", str(dry / "workload-1.log")],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((dry / "report.json").read_text(encoding="utf-8"))
        for edge in report["edges"]:
            self.assertNotIn("coverage", edge)
            self.assertEqual(edge["entries"]["coverage"]["state"], "counted")
        passed, detail = self.oracle.gate_workload_ledger(self.oracle.Evidence(dry))
        self.assertTrue(passed, detail)

    def test_vehicle_diagnostics_are_opt_in_in_both_observer_branches(self):
        vehicle = ROOT / "scripts" / "system-manifest-soak.sh"
        parsed = subprocess.run(["sh", str(vehicle), "--diagnostics", "--help"],
                                capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        text = vehicle.read_text(encoding="utf-8")
        start = text.index('if [ "$MODE" = live ]; then\n    set -- "$INSTALLED_COPY" inventory')
        end = text.index('T_SPAWN=$(mono_ns)', start)
        command = text[start:end] + '\nprintf \'%s\\n\' "$OBS_ARGV_JSON"\n'
        work = self.base / "observer-argv"
        for mode in ("live", "dry-run"):
            for requested in (False, True):
                with self.subTest(mode=mode, requested=requested):
                    env = dict(os.environ, MODE=mode, WORK=str(work),
                               INSTALLED_COPY="/installed/p11scope", STUB_COPY="/stub.py",
                               OBSERVER_DURATION="30", CALLERS="2",
                               DIAGNOSTICS="1" if requested else "0")
                    result = subprocess.run(["sh", "-c", command], env=env,
                                            capture_output=True, text=True, check=False, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    argv = json.loads(result.stdout)
                    self.assertEqual(argv.count("--diagnostics"), int(requested))
                    if requested:
                        self.assertEqual(argv[argv.index("--diagnostics") + 1],
                                         str(work / "count-diagnostics.jsonl"))
                    self.assertEqual(argv[argv.index("--duration") + 1], "30")
                    self.assertEqual(argv[argv.index("-o") + 1], str(work / "report.json"))

    def test_stub_accepts_opt_in_diagnostics_without_native_evidence(self):
        dry = make_green(self.base / "stub-diagnostics", horizon=8, mode="dry-run")
        manifest = dry / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "fixtures" /
                                       "system-manifest-soak-stub.py"),
             "inventory", "--system", "--manifest", str(manifest),
             "--duration", "1", "--attach-delay", "0", "--json",
             "-o", str(dry / "report.json"),
             "--diagnostics", str(dry / "count-diagnostics.jsonl"),
             "--loopback-log", str(dry / "workload-0.log"),
             "--loopback-log", str(dry / "workload-1.log")],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((dry / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["soak_stub"]["mode"], "dry-run-loopback")
        self.assertEqual(report["semantic_edges"], [])
        passed, detail = self.oracle.gate_workload_ledger(self.oracle.Evidence(dry))
        self.assertTrue(passed, detail)

    def test_vehicle_supports_fedora_softhsm_layout(self):
        vehicle = ROOT / "scripts" / "system-manifest-soak.sh"
        text = vehicle.read_text(encoding="utf-8")
        self.assertIn("/usr/lib64/pkcs11/libsofthsm2.so", text,
                      "the soak vehicle must try the Fedora SoftHSM layout")

    def test_red_stop_rc(self):
        target = mutate_copy(self.green, "leg-stop-rc", lambda target: rewrite_json(
            target / "run.json", lambda run: run["observer"].update({"exit": 1})))
        self.assert_red_only(self.evaluate(target), "finite_stop")

    def test_red_stop_timeout(self):
        target = mutate_copy(self.green, "leg-stop-timeout", lambda target: rewrite_json(
            target / "run.json", lambda run: run["observer"].update({"timed_out": True})))
        self.assert_red_only(self.evaluate(target), "finite_stop")

    def test_red_stop_short_window(self):
        def shrink(target):
            rewrite_json(target / "run.json", lambda run: run["timing"].update(
                {"end_mono_ns": run["timing"]["start_mono_ns"] + 1_799_000_000_000}))
        self.assert_red_only(self.evaluate(mutate_copy(self.green, "leg-short", shrink)),
                             "finite_stop")

    def test_red_ledger_mismatch(self):
        def inflate(target):
            rewrite_json(target / "report.json",
                         lambda report: report["edges"][0]["entries"].update({"count": 1}))
        self.assert_red_only(self.evaluate(mutate_copy(self.green, "leg-mismatch", inflate)),
                             "workload_ledger")

    def test_green_entry_coverage_ignores_unrelated_edge_copy(self):
        rewrite_json(self.green / "report.json", lambda report: report["edges"][0].update(
            {"coverage": {"state": "unknown", "lossy": True}}))
        self.assert_gate(self.evaluate(self.green), "workload_ledger", True)

    def test_red_ledger_entry_coverage_cannot_be_masked_by_edge_copy(self):
        for state in ("unknown", "refused", "witnessed", "watched_no_use"):
            with self.subTest(state=state):
                def change_coverage(target):
                    def change(report):
                        for edge in report["edges"]:
                            edge["coverage"] = {"state": "counted", "lossy": False}
                        report["edges"][0]["entries"]["coverage"].update(
                            {"state": state, "lossy": None, "reason": "loss"})
                    rewrite_json(target / "report.json", change)
                target = mutate_copy(self.green, f"leg-coverage-{state}", change_coverage)
                verdict = self.evaluate(target)
                self.assert_red_only(verdict, "workload_ledger")
                self.assertIn(state, verdict["gates"]["workload_ledger"]["detail"])

    def test_red_ledger_lossy_entry_coverage(self):
        def mark_lossy(report):
            for edge in report["edges"]:
                edge["coverage"] = {"state": "counted", "lossy": False}
            report["edges"][0]["entries"]["coverage"]["lossy"] = True
        rewrite_json(self.green / "report.json", mark_lossy)
        self.assert_red_only(self.evaluate(self.green), "workload_ledger")

    def test_red_ledger_missing_entry_coverage_ignores_edge_copy(self):
        def drop_coverage(report):
            for edge in report["edges"]:
                edge["coverage"] = {"state": "counted", "lossy": False}
            report["edges"][0]["entries"].pop("coverage")
        rewrite_json(self.green / "report.json", drop_coverage)
        self.assert_red_only(self.evaluate(self.green), "workload_ledger")

    def test_red_ledger_missing_done(self):
        def drop_done(target):
            path = target / "workload-0.log"
            kept = [line for line in path.read_text(encoding="utf-8").splitlines()
                    if not line.startswith("DONE ")]
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        self.assert_red_only(self.evaluate(mutate_copy(self.green, "leg-nodone", drop_done)),
                             "workload_ledger")

    def test_red_ledger_foreign_edge(self):
        def add_foreign(target):
            rewrite_json(target / "report.json", lambda report: report["edges"].append({
                "caller": "c9", "module": "m0",
                "entries": {"count": 5, "coverage": {"state": "counted", "lossy": False}}}))
        self.assert_red_only(self.evaluate(mutate_copy(self.green, "leg-foreign", add_foreign)),
                             "workload_ledger")

    def test_red_ledger_malformed_row_is_structured_fail(self):
        def corrupt(target):
            path = target / "workload-0.log"
            text = path.read_text(encoding="utf-8")
            path.write_text(text + "LEDGER this-token-has-no-equals-sign\n",
                            encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-malformed", corrupt)),
            "workload_ledger")

    def test_red_loss_unconserved(self):
        def break_conservation(target):
            (target / "observer.stderr").write_text(
                "p11scope: semantic calls: collected 100, joined 40, shed 30, "
                "bindings 2, refused 0\n", encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-unconserved", break_conservation)),
            "loss_accounting")

    def test_red_loss_silent_shed(self):
        silent = make_green(self.base / "silent-shed", shed=50)
        self.assert_red_only(self.evaluate(silent), "loss_accounting")

    def test_red_loss_silent_unrouted(self):
        silent = make_green(self.base / "silent-unrouted", unrouted=7)
        self.assert_red_only(self.evaluate(silent), "loss_accounting")

    def test_red_loss_unnamed_gap(self):
        def blank_subject(target):
            rewrite_json(target / "report.json", lambda report: report.update(
                {"gaps": [{"subject": "", "reason": "x"}]}))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-unnamed", blank_subject)),
            "loss_accounting")

    def test_red_loss_suppressed(self):
        def suppress(target):
            rewrite_json(target / "report.json", lambda report: report.update(
                {"gaps_suppressed": 3}))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-suppressed", suppress)),
            "loss_accounting")

    def test_red_loss_refused_endpoints_silent(self):
        def refuse(target):
            rewrite_json(target / "report.json", lambda report: report["budgets"][
                "endpoints"].update({"refused": 4}))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-refused", refuse)),
            "loss_accounting")

    def test_red_loss_budget_refusal_needs_named_subject(self):
        def refuse_unrelated(target):
            rewrite_json(target / "report.json", lambda report: (
                report["budgets"]["endpoints"].update({"refused": 4}),
                report.update({"gaps": [{"subject": "kernel threads",
                                          "reason": "verified absence"}]})))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-refused-unrelated",
                                      refuse_unrelated)),
            "loss_accounting")

    def test_green_budget_refusal_with_named_gap_passes(self):
        counted = make_green(
            self.base / "budget-named",
            gaps=[("endpoint budget exhausted", "registry retains at most 8192")])
        rewrite_json(counted / "report.json", lambda report: report["budgets"][
            "endpoints"].update({"refused": 4}))
        verdict = self.evaluate(counted)
        self.assertEqual(verdict["verdict"], "PASS", json.dumps(verdict["gates"]))

    def test_red_resources_over_bound(self):
        def fatten(target):
            rows = [(n * 1000, 300_000, 300_000, 40) for n in range(1900)]
            (target / "resources.tsv").write_text(_resources(rows), encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-fat", fatten)),
            "resource_accounting")

    def test_red_resources_steady_growth(self):
        def ramp(target):
            rows = [(n * 1000, 50_000 + n * 100, 60_000 + n * 100, 40)
                    for n in range(1900)]
            (target / "resources.tsv").write_text(_resources(rows), encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-ramp", ramp)),
            "resource_accounting")

    def test_red_resources_fd_growth(self):
        def leak(target):
            rows = [(n * 1000, 52_000, 54_000, 40 + n) for n in range(1900)]
            (target / "resources.tsv").write_text(_resources(rows), encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-fds", leak)),
            "resource_accounting")

    def test_red_resources_short_trace(self):
        def truncate(target):
            (target / "resources.tsv").write_text(
                _resources([(0, 52_000, 54_000, 40)]), encoding="utf-8")
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-trace", truncate)),
            "resource_accounting")

    def test_red_journal_populated_claim(self):
        def populate(target):
            rewrite_json(target / "report.json", lambda report: report.update(
                {"object_observations": {"status": "populated"}}))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-populated", populate)),
            "journal_disclosure")

    def test_red_clean_workload_exit(self):
        def fail_workload(target):
            rewrite_json(target / "run.json",
                         lambda run: run["workloads"][0].update({"exit": 2}))
        self.assert_red_only(
            self.evaluate(mutate_copy(self.green, "leg-wexit", fail_workload)),
            "clean_exit")

    def test_red_missing_evidence_is_structured_fail(self):
        empty = self.base / "empty"
        empty.mkdir()
        verdict = self.evaluate(empty)
        self.assertEqual(verdict["verdict"], "FAIL")
        for gate in self.oracle.GATES:
            self.assert_gate(verdict, gate, False)

    def test_red_missing_report_is_hang_verdict(self):
        hung = mutate_copy(self.green, "leg-noreport",
                           lambda target: (target / "report.json").unlink())
        verdict = self.evaluate(hung)
        self.assertEqual(verdict["verdict"], "FAIL")
        for gate in self.oracle.GATES:
            self.assert_gate(verdict, gate, False)
        self.assertIn("report.json", verdict["gates"]["finite_stop"]["detail"])
        self.assertEqual(verdict["cell_id"], "soak-manifest.1800s")


if __name__ == "__main__":
    unittest.main()
