# SPDX-License-Identifier: GPL-3.0-or-later
"""Stop-race oracle controls: seeded sweep trials and the newcomer burst."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/stop-race-oracle.py"
NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
OWNED = {"dev": [8, 1], "ino": 71, "sha256": "a" * 64}
FOREIGN = {"dev": [8, 1], "ino": 72, "sha256": "b" * 64}
LOSS_COUNTERS = ("start_insert_failures", "unmatched_returns", "rv_update_failures",
                 "cgroup_scope_failures", "abi_refusals", "malformed_records",
                 "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures",
                 "discovery_truncated", "task_uprobe_link_losses")
VERDICT_COUNTERS = (
    "semantic_capture_failures", "unregistered_mechanisms", "template_tail_failures",
    "process_tracking_fallbacks", "process_tracking_failures", "process_tracking_evictions",
    "state_reconciliations", "session_cancel_ambiguities", "session_cancel_unknown_flags",
    "operation_state_imports", "auth_state_ambiguities", "async_target_failures", "async_orphans",
    "async_duplicates", "async_evictions", "fork_state_ambiguities", "semantic_state_drops",
    "semantic_history_drops", "pending_at_end", "orphan_ops", "unmatched_closes",
    "shape_decode_failures", "shape_decode_total_failures", "discovery_conflicts",
    "discovery_uncorroborated", "module_ambiguous", "semantic_unverified_slots",
    "module_unresolved_slots", "unprotected_live_windows", "pause_partial", "vendor_interfaces")


def provider_pin():
    return dict(OWNED,
                file_identity={"dev": [0, 38], "ino": 71, "size": 8192,
                               "mtime_ns": 123, "ctime_ns": 456},
                mapping={"dev": [8, 1], "ino": 71, "file_offset": 0,
                         "length": 4096, "permissions": "r--p"})


def profile_report(system=False, calls=7):
    scope = "system" if system else "pid"
    report = {"schema": "p11scope/observed-profile/v3",
              "lane": "profile", "capture": {"scope": scope, "mode": "profile"},
              "functions": [{"names": [name], "calls": calls, "errors": 0, "in_flight": 0,
                             "pending_returns": 0,
                             "module": dict(OWNED), "module_ambiguous": False,
                             "module_unresolved": False,
                             "target": {"object": dict(OWNED), "file_offset": 4096 + i * 16}}
                            for i, name in enumerate(NAMES)],
              "evidence": {"completeness": "COMPLETE", "verdict_detail": "clean_proven",
                           "in_flight_at_end": 0, "event_loss": 0,
                           "discovery": [dict(OWNED, path="/owned.so", tables=[{}])],
                           "modules_skipped": []}}
    report["evidence"].update({key: 0 for key in LOSS_COUNTERS + VERDICT_COUNTERS})
    report["evidence"].update(
        slots=6, scan_unavailable=None, attach_failures=[], skipped=[], surfaces=[], aliased=[],
        interface_list="absent", provider_changed=False, templates_truncated=False,
        scheduling={"terminal_drain_truncated": False, "sink_dropped_bytes": 0,
                    "newcomer_queue": {"admitted": 0, "admitted_unknown": 0,
                                       "max_admitted_age_ms": None, "mean_admitted_age_ms": None,
                                       "pending": 0, "oldest_pending_age_ms": None,
                                       "dropped": 0, "dropped_unknown": 0,
                                       "max_dropped_age_ms": None, "marks_dropped": 0}},
        loader_discovery={"strategies": {"debug_state_every_hit": 0, "dlopen_return": 0,
                                         "unavailable": 0},
                          "dlopen_timing": {"qualified_pre_constructor": 0, "known_pre_relocation": 0,
                                            "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_timing": {"qualified_pre_constructor": 0,
                                                 "known_pre_relocation": 0,
                                                 "unproven": 0, "none": 0, "pause_protected": 0},
                          "initial_set_capture": {"eligible": 0, "none": 0, "pause_protected": 0},
                          "state_read_failures": 0, "hits": 0},
        pid_namespace={"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
        drain_proven=True,
        stop_quiescence={"state": "proven", "post_q_events": False, "post_q_discovery": False})
    report["evidence"]["gap_classes"] = {
        "observation": {"status": "exact", "causes": []},
        "attribution": {"status": "attested", "causes": []},
        "semantics": {"status": "complete", "causes": []},
        "open_calls": 0, "settlement": "proven", "stdout_data_sink": False}
    report["evidence"]["kernel_control"] = {
        "capture_halted": False, "owner_poison": [], "owner_admission_failures": 0,
        "identity_unavailable": 0, "identity_budget_exhausted": False,
        "root_affiliation_failures": []}
    report["evidence"].update(
        interface_selection={"selection_truncated": False, "providers": [],
                             "standard_exports": [], "inventory_surfaces": [], "tuples": []},
        attach_mechanisms=["per-offset"],
        attach_backend={"selection": "singles", "fallback": None,
                        "scope_filter": None if system else "perf-task+bpf"},
        pid_descendant_gaps=0, multi_rebuild_gaps=0)
    return report


def inventory_report(pid=123, count_per_edge=42):
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "system",
        "callers": [{"id": "c0", "pid": pid}],
        "modules": [{"id": "m0",
                     "identity": {"device": {"major": 8, "minor": 1}, "inode": 71,
                                  "sha256": "a" * 64}}],
        "edges": [{"caller": "c0", "module": "m0",
                   "entries": {"count": count_per_edge, "in_flight": False}}],
        "gaps": [],
    }


def ledger_lines(calls=7, complete=True, pid=123):
    lines = ["TARGET " + json.dumps({"name": name, "dev": [8, 1], "ino": 71,
                                     "file_offset": 4096 + i * 16})
             for i, name in enumerate(NAMES)]
    lines.append("READY pid=%d" % pid)
    lines.append("LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v1", "pid": pid, "complete": complete,
        "functions": [{"name": name, "attempts": calls, "successful": calls}
                      for name in NAMES]}))
    return lines


def stderr_text(pending=0, oldest="n/a", cleanup=True, panic=False, storage_refusal=False,
                native_stopped=True):
    lines = ["p11scope: capturing: single-shot\n"]
    if native_stopped:
        lines.append("p11scope: native capture stopped after 1 pass: 68 endpoints attached "
                     "(uprobe-multi links), 0 failed; retirement closed (3 of 3 links closed); "
                     "settlement unsettled\n")
    if panic:
        lines.append("thread 'main' panicked at src/main.rs:29\n")
    if storage_refusal:
        lines.append("p11scope: system: provider_storage_refused\n")
    lines.append("p11scope: timing: stages scan=6ms pin=1ms bind=0ms plan=0ms merge=0ms "
                 "projection=0ms attach=7ms drain=1ms cleanup=0ms (unknown-clock spans: 0); "
                 "longest op: attach/attach_dynamic_loader@7ms; "
                 "inter-drain gap p50/p99/max: 2ms/2ms/2ms (6693 samples); "
                 "newcomer queue: admitted 0 (max/mean age n/a/n/a), pending %d (oldest %s), "
                 "dropped 0 (max age n/a); tails: 0 published, 14 skipped; "
                 "rss start/readiness/end/max: 32524/65684/74068/74068 kB\n"
                 % (pending, oldest))
    if cleanup:
        lines.append("p11scope: cleanup completed, 2/2 links released, 0 s\n")
    return "".join(lines)


class OracleTests(unittest.TestCase):
    def run_case(self, mutate=None, *, mode="sweep", command="profile-pid",
                 ledger_complete=1, exit_code=0, seed=11, offset_ms=37,
                 newcomer_function="C_GenerateRandom", provider_newcomers=16,
                 allow_storage_refusal=False, after_pin=None, detail_substr=None, want=0):
        report = profile_report(system=command == "profile-system")
        if command == "inventory-system":
            report = inventory_report(count_per_edge=42)
        workload = ledger_lines()
        stderr = stderr_text()
        pin = provider_pin()
        if mutate:
            box = {"report": report, "workload": workload, "stderr": stderr, "pin": pin}
            mutate(box)
            report, workload, stderr, pin = (box["report"], box["workload"],
                                             box["stderr"], box["pin"])
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            report_path = tmp / "report.json"
            report_path.write_text(report if isinstance(report, str) else json.dumps(report))
            workload_path = tmp / "workload.wl"
            workload_path.write_text(workload if isinstance(workload, str)
                                     else "\n".join(workload) + "\n")
            stderr_path = tmp / "observer.stderr"
            stderr_path.write_text(stderr)
            before_path, after_path = tmp / "before.json", tmp / "after.json"
            before_path.write_text(json.dumps(pin))
            after_path.write_text(json.dumps(after_pin if after_pin is not None else pin))
            args = [sys.executable, "-I", str(ORACLE), "--mode", mode,
                    "--command", command, "--report", str(report_path),
                    "--workload", str(workload_path), "--stderr", str(stderr_path),
                    "--exit", str(exit_code), "--seed", str(seed),
                    "--offset-ms", str(offset_ms),
                    "--ledger-complete", str(ledger_complete),
                    "--provider-before", str(before_path),
                    "--provider-after", str(after_path)]
            if mode == "burst":
                args += ["--newcomer-function", newcomer_function,
                         "--provider-newcomers", str(provider_newcomers)]
            if allow_storage_refusal:
                args += ["--allow-storage-refusal"]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["pass"], want == 0)
        if detail_substr is not None:
            self.assertIn(detail_substr, result["detail"])
        return result

    def test_sweep_complete_equal_counts_pass(self):
        result = self.run_case()
        self.assertIn("seed=11", result["detail"])
        self.assertIn("offset_ms=37", result["detail"])

    def test_sweep_complete_under_counts_fail(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 6
        self.run_case(mutate, want=1)

    def test_sweep_racing_under_counts_pass(self):
        def mutate(box):
            for row in box["report"]["functions"]:
                row["calls"] = 3
        self.run_case(mutate, ledger_complete=0)

    def test_sweep_racing_over_counts_fail(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 8
        self.run_case(mutate, ledger_complete=0, want=1)

    def test_sweep_racing_missing_row_counts_as_zero(self):
        def mutate(box):
            box["report"]["functions"] = box["report"]["functions"][1:]
        self.run_case(mutate, ledger_complete=0)

    def test_sweep_racing_unknown_row_counts_join_the_total(self):
        def mutate(box):
            row = dict(box["report"]["functions"][0])
            row["target"] = {"object": None, "file_offset": 4096}
            row["calls"] = 1
            box["report"]["functions"].append(row)
        self.run_case(mutate, ledger_complete=0, want=1)

    def test_sweep_nonzero_exit_fails(self):
        self.run_case(exit_code=130, want=1)

    def test_sweep_missing_cleanup_fails(self):
        self.run_case(lambda box: box.update(stderr=stderr_text(cleanup=False)), want=1)

    def test_sweep_panic_fails(self):
        self.run_case(lambda box: box.update(stderr=stderr_text(panic=True)), want=1)

    def test_sweep_storage_refusal_fails_unless_allowed(self):
        mutate = lambda box: box.update(stderr=stderr_text(storage_refusal=True))
        self.run_case(mutate, want=1)
        self.run_case(mutate, allow_storage_refusal=True)

    def test_sweep_unparseable_report_fails(self):
        self.run_case(lambda box: box.update(report="{nope"), want=1)

    def test_sweep_complete_lossy_observation_passes_with_noted_detail(self):
        # S3 judges counts plus hygiene: a lossy capture with holding
        # counts passes, but the detail must name the observation class
        # and the loss counter, never silently.
        def mutate(box):
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
        result = self.run_case(mutate, detail_substr="obs=lossy[discovery_truncated]")
        self.assertIn("loss=discovery_truncated", result["detail"])

    def test_sweep_complete_in_flight_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["in_flight"] = 1
        self.run_case(mutate, want=1)

    def test_sweep_scope_mismatch_fails(self):
        def mutate(box):
            box["report"]["capture"]["scope"] = "system"
        self.run_case(mutate, want=1)

    def test_sweep_provider_change_fails(self):
        after = provider_pin()
        after["sha256"] = "c" * 64
        self.run_case(after_pin=after, want=1)

    def test_sweep_pin_mismatch_fails(self):
        self.run_case(lambda box: box.update(pin=dict(
            provider_pin(), sha256="c" * 64,
            mapping=dict(provider_pin()["mapping"]))), want=1)

    def test_sweep_foreign_target_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["target"]["object"] = FOREIGN
        self.run_case(mutate, want=1)

    def test_sweep_run_partial_ledger_races(self):
        def mutate(box):
            payload = json.loads(box["workload"][-1][len("LEDGER "):])
            payload["complete"] = False
            for row in payload["functions"]:
                row.update(attempts=4, successful=4)
            box["workload"][-1] = "LEDGER " + json.dumps(payload)
            for row in box["report"]["functions"]:
                row["calls"] = 4
        self.run_case(mutate, command="run", ledger_complete=0)

    def test_sweep_inventory_complete_equal_pass(self):
        self.run_case(command="inventory-system")

    def test_sweep_inventory_racing_under_pass(self):
        def mutate(box):
            box["report"]["edges"][0]["entries"]["count"] = 20
        self.run_case(mutate, command="inventory-system", ledger_complete=0)

    def test_sweep_inventory_racing_over_fails(self):
        def mutate(box):
            box["report"]["edges"][0]["entries"]["count"] = 43
        self.run_case(mutate, command="inventory-system", ledger_complete=0, want=1)

    def test_sweep_inventory_missing_module_fails(self):
        def mutate(box):
            box["report"]["modules"][0]["identity"]["inode"] = 999
        self.run_case(mutate, command="inventory-system", want=1)

    def test_sweep_inventory_needs_no_cleanup_line(self):
        self.run_case(lambda box: box.update(stderr=stderr_text(cleanup=False)),
                      command="inventory-system")

    def test_sweep_inventory_missing_native_stopped_fails(self):
        self.run_case(lambda box: box.update(stderr=stderr_text(native_stopped=False)),
                      command="inventory-system", want=1,
                      detail_substr="missing native-stopped line")

    def test_burst_exact_all_counted_pass(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 16
        self.run_case(mutate, mode="burst", command="profile-system")

    def test_burst_pending_with_exact_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 8
            box["report"]["evidence"]["scheduling"]["newcomer_queue"]["pending"] = 8
            box["report"]["evidence"]["scheduling"]["newcomer_queue"][
                "oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system", want=1)

    def test_burst_pending_with_lossy_covered_pass(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 8
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
            evidence["scheduling"]["newcomer_queue"]["pending"] = 8
            evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system")

    def test_burst_pending_with_ambient_lossy_cause_fails(self):
        # A pending backlog covers discovery-side loss only; ambient
        # churn (descendant gaps, unprotected windows, pause windows)
        # must fail even when every newcomer is counted or pending.
        for cause, counter, value in (
                ("pid_descendant_gaps", "pid_descendant_gaps", 5),
                ("unprotected_live_windows", "unprotected_live_windows", 1),
                ("pause_partial", "pause_partial", 1)):
            def mutate(box, cause=cause, counter=counter, value=value):
                box["report"]["functions"][0]["calls"] = 7 + 8
                evidence = box["report"]["evidence"]
                evidence["completeness"] = "PARTIAL"
                evidence[counter] = value
                evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                          "causes": [cause]}
                evidence["verdict_detail"] = "concrete_gap"
                evidence["scheduling"]["newcomer_queue"]["pending"] = 8
                evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
                box["stderr"] = stderr_text(pending=8, oldest="2ms")
            self.run_case(mutate, mode="burst", command="profile-system",
                          want=1, detail_substr="non-newcomer lossy cause")

    def test_burst_pending_uncovered_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 2
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
            evidence["scheduling"]["newcomer_queue"]["pending"] = 8
            evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system", want=1)

    def test_burst_lossy_without_pending_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 16
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
        self.run_case(mutate, mode="burst", command="profile-system", want=1)

    def test_burst_long_workload_deficit_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 16
            box["report"]["functions"][1]["calls"] = 6
        self.run_case(mutate, mode="burst", command="profile-system", want=1)

    def test_burst_multi_function_newcomers_covered_pass(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 16
            box["report"]["functions"][1]["calls"] = 7 + 10
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
            evidence["scheduling"]["newcomer_queue"]["pending"] = 8
            evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system",
                      newcomer_function="C_GenerateRandom,C_DigestInit")

    def test_burst_multi_function_newcomer_uncovered_fails(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 16
            box["report"]["functions"][1]["calls"] = 7 + 2
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
            evidence["scheduling"]["newcomer_queue"]["pending"] = 8
            evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system",
                      newcomer_function="C_GenerateRandom,C_DigestInit", want=1,
                      detail_substr="neither counted nor pending: C_DigestInit")

    def test_burst_stderr_pending_must_match_report(self):
        def mutate(box):
            box["report"]["functions"][0]["calls"] = 7 + 8
            evidence = box["report"]["evidence"]
            evidence["completeness"] = "PARTIAL"
            evidence["discovery_truncated"] = 1
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["discovery_truncated"]}
            evidence["verdict_detail"] = "concrete_gap"
            evidence["scheduling"]["newcomer_queue"]["pending"] = 8
            evidence["scheduling"]["newcomer_queue"]["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=7, oldest="2ms")
        self.run_case(mutate, mode="burst", command="profile-system", want=1)


    def test_fail_details_name_the_cause(self):
        def lossy(evidence):
            evidence["completeness"] = "PARTIAL"
            evidence["provider_changed"] = True
            evidence["gap_classes"]["observation"] = {"status": "lossy",
                                                      "causes": ["provider_changed"]}
            evidence["verdict_detail"] = "concrete_gap"

        def under(box):
            box["report"]["functions"][0]["calls"] = 6
        self.run_case(under, want=1, detail_substr="differs from independent ledger")

        def over(box):
            box["report"]["functions"][0]["calls"] = 8
        self.run_case(over, ledger_complete=0, want=1,
                      detail_substr="exceeds independent ledger")

        def unknown_joins(box):
            row = dict(box["report"]["functions"][0])
            row["target"] = {"object": None, "file_offset": 4096}
            row["calls"] = 1
            box["report"]["functions"].append(row)
        self.run_case(unknown_joins, ledger_complete=0, want=1,
                      detail_substr="exceeds independent ledger")

        def lossy_complete(box):
            lossy(box["report"]["evidence"])
        result = self.run_case(lossy_complete, detail_substr="obs=lossy[provider_changed]")
        self.assertIn("loss=-", result["detail"])

        def pending_exact(box):
            box["report"]["functions"][0]["calls"] = 7 + 8
            queue = box["report"]["evidence"]["scheduling"]["newcomer_queue"]
            queue["pending"] = 8
            queue["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(pending_exact, mode="burst", command="profile-system", want=1,
                      detail_substr="pending coexists with exact")

        def uncovered(box):
            box["report"]["functions"][0]["calls"] = 7 + 2
            lossy(box["report"]["evidence"])
            queue = box["report"]["evidence"]["scheduling"]["newcomer_queue"]
            queue["pending"] = 8
            queue["oldest_pending_age_ms"] = 2
            box["stderr"] = stderr_text(pending=8, oldest="2ms")
        self.run_case(uncovered, mode="burst", command="profile-system", want=1,
                      detail_substr="neither counted nor pending")

        def inventory_over(box):
            box["report"]["edges"][0]["entries"]["count"] = 43
        self.run_case(inventory_over, command="inventory-system", ledger_complete=0, want=1,
                      detail_substr="exceed independent ledger")


if __name__ == "__main__":
    unittest.main()

